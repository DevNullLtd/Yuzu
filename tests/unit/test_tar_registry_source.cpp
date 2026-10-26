/**
 * test_tar_registry_source.cpp -- the `registry` cursor-model TAR source
 * (tar_registry_parsers.hpp pure core + tar_registry_source.{hpp,cpp}).
 *
 * Three layers: (1) the pure core -- paths, rendering, baselines, windows, the diff,
 * correlation, the stitch with its settle hold and loss epochs, the dirty table, the
 * seq-identified event buffer, record keys and codecs; (2) the collect() state machine
 * over an injected reader and a real ephemeral TarDatabase, on every platform; (3) the
 * [windows] live cases (kingsley, elevated) that run the real key watch and the real
 * Kernel-Registry ETW session. No test sleeps: a live notification or event is awaited
 * on a condition variable with a deadline, and time is the injected clock.
 */

#include "tar_cursor.hpp"
#include "tar_db.hpp"
#include "tar_registry_parsers.hpp"
#include "tar_registry_source.hpp"
#include "tar_schema_registry.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <thread>
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
#include <win_str.hpp>
#endif

namespace fs = std::filesystem;
using namespace yuzu::tar;
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
                    std::string image = "svc.exe", std::uint64_t key_object = 1,
                    std::uint32_t tid = 1) {
    RegistryEtwEvent e;
    e.ts100ns = ts;
    e.pid = pid;
    e.tid = tid;
    e.image = std::move(image);
    e.key_object = key_object;
    e.op = op;
    e.value = std::move(value);
    e.type = type;
    e.size = size;
    return e;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// Pure core
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("normalise_registry_path maps only the current control set", "[tar][registry][pure]") {
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
          "[tar][registry][pure]") {
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

TEST_CASE("is_user_hive_name accepts SID-named hives only", "[tar][registry][pure]") {
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

TEST_CASE("render_reg_data renders each registry type", "[tar][registry][pure]") {
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

TEST_CASE("baseline_entry_from_bytes hashes every byte read (R8)", "[tar][registry][pure]") {
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
          "[tar][registry][pure]") {
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
          "[tar][registry][pure]") {
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

TEST_CASE("RegistryReadBudget caps keys and values and bytes (R9)", "[tar][registry][pure]") {
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
          "[tar][registry][pure]") {
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
          "[tar][registry][pure]") {
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
        // so it is correlated. This is the limit docs/user-manual/tar.md states: attr:corr is a
        // lead to verify against $Process_Live, not proof.
        const auto a = attribute_candidate(c, {ev(150, 4242, RegistryEtwOp::Set, "Start")});
        CHECK(a.kind == AttributionKind::Corr);
        CHECK(a.pid == 4242);
    }
    SECTION("key_removed is never attributed, even beside a DeleteKey and a matching DeleteValue") {
        const auto kr = cand("key_removed", "", 0, 0, 100, 200);
        CHECK(attribute_candidate(kr, {ev(150, 9, RegistryEtwOp::DeleteKey, "", 0, 0, "x.exe", 55),
                                       ev(150, 9, RegistryEtwOp::DeleteValue, "", 0, 0, "x.exe", 55)})
                 .kind == AttributionKind::None);
    }
}

TEST_CASE("dedupe_registry_events drops a repeated delivery of one event", "[tar][registry][pure]") {
    const auto e = ev(105, 5, RegistryEtwOp::Set, "Start");
    auto other_tid = e;
    other_tid.tid = 2; // a different thread's write is a different event
    const auto out = dedupe_registry_events({e, e, other_tid});
    CHECK(out.size() == 2);
}

TEST_CASE("stitch_registry_tick: rows, counters, the settle hold and what is NOT recorded",
          "[tar][registry][pure]") {
    const StitchFlags on{true, false, 0};
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
           ev(101 * SEC, 5, RegistryEtwOp::Set, "Start", 4, 4, "p.exe", 10),
           ev(102 * SEC, 5, RegistryEtwOp::Set, "Start", 4, 4, "p.exe", 20),
           ev(103 * SEC, 5, RegistryEtwOp::Set, "Secret", 1, 8, "p.exe", 20)};
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
           {kr}, {ev(105 * SEC, 9, RegistryEtwOp::DeleteKey, "", 0, 0, "x.exe", 55)}, {}, on, now, 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].detail == "attr:none");
        CHECK(r.rows[0].actor_pid == 0);
    }
    SECTION("duplicate delivery is one attribution") {
        const auto e = ev(105 * SEC, 5, RegistryEtwOp::Set, "Start");
        const auto r = stitch_registry_tick({c}, {e, e}, {}, on, now, 1);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].detail == "attr:corr");
    }
    SECTION("settle hold: 4 s after the window stays held, 5 s finalises") {
        const auto held = stitch_registry_tick({c}, {}, {}, on, c.window_hi + 4 * SEC, 1);
        CHECK(held.rows.empty());
        CHECK(held.held_next.size() == 1);
        const auto done = stitch_registry_tick({c}, {}, {}, on, c.window_hi + 5 * SEC, 1);
        CHECK(done.rows.size() == 1);
        CHECK(done.held_next.empty());
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
        auto r = stitch_registry_tick({c}, evs, hit, StitchFlags{false, false, 0}, now, 1);
        CHECK(r.rows[0].detail == "attr:off"); // off beats degraded
        CHECK(r.rows[0].actor_pid == 0);
        r = stitch_registry_tick({c}, evs, hit, StitchFlags{false, true, 0}, now, 1);
        CHECK(r.rows[0].detail == "attr:lost-restart"); // lost-restart beats off
        // the buffer began after the window opened -> the early part of the window is unobserved
        r = stitch_registry_tick({c}, evs, {}, StitchFlags{true, false, 105 * SEC}, now, 1);
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
        const auto off = stitch_registry_tick({c}, {}, {}, StitchFlags{false, false, 0}, now, 1);
        REQUIRE(corr.rows.size() == 1);
        CHECK(corr.rows[0].record_key == none.rows[0].record_key);
        CHECK(corr.rows[0].record_key == off.rows[0].record_key);
        CHECK(corr.rows[0].record_key ==
              registry_diff_record_key(c.source, c.observed_at, c.action, c.key, c.value));
    }
}

TEST_CASE("loss epochs: age out, intersect on a (lo, hi] window, collapse past the cap",
          "[tar][registry][pure]") {
    std::vector<LossEpoch> epochs{{1, 2}, {10, 20}};
    age_loss_epochs(epochs, 5);
    CHECK(epochs == std::vector<LossEpoch>{{10, 20}});
    for (std::int64_t i = 0; i < 64; ++i) // 1 + 64 = 65 epochs
        append_loss_epoch(epochs, {100 + i * 10, 105 + i * 10});
    REQUIRE(epochs.size() == 1); // past kLossEpochCap: one covering interval
    CHECK(epochs[0].lo == 10);
    CHECK(epochs[0].hi == 100 + 63 * 10 + 5);

    const RegistryWindow w{100, 200};
    CHECK(window_intersects(w, LossEpoch{200, 300}));       // the epoch starts at the window's end
    CHECK_FALSE(window_intersects(w, LossEpoch{201, 300})); // after it
    CHECK_FALSE(window_intersects(w, LossEpoch{50, 100}));  // ends where the window opens
    CHECK(window_intersects(w, LossEpoch{50, 101}));
}

TEST_CASE("RegistryEtwBuffer retires by sequence identity and counts what it evicts (R4)",
          "[tar][registry][pure]") {
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
    SECTION("pause discards and refuses; resume clears and accepts again") {
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
        b.clear();
        CHECK(b.size() == 0);
    }
    SECTION("the bounded wait sees a matching event and never polls") {
        RegistryEtwBuffer b;
        const auto is_v = [](const RegistryEtwEvent& e) { return e.value == "v"; };
        CHECK_FALSE(b.wait_for_event(is_v, std::chrono::steady_clock::now())); // past deadline: at once
        b.push(ev(1, 1, RegistryEtwOp::Set, "v"));
        CHECK(b.wait_for_event(is_v, std::chrono::steady_clock::now() + std::chrono::seconds(30)));
        CHECK_FALSE(b.wait_for_event([](const RegistryEtwEvent& e) { return e.value == "w"; },
                                     std::chrono::steady_clock::now()));
    }
}

TEST_CASE("retention rule (R5): the watermark and held windows decide what is released",
          "[tar][registry][pure]") {
    std::map<std::string, RegistryRootState> roots;
    CHECK(retention_watermark(roots) == std::numeric_limits<std::int64_t>::max()); // no roots
    roots["a"].window_base = 100;
    roots["b"].window_base = 0; // never completely read
    CHECK(retention_watermark(roots) == 0);
    roots["b"].window_base = 200;
    CHECK(retention_watermark(roots) == 100);

    RegistryEtwBuffer buf;
    for (std::int64_t ts : {50, 90, 100, 150})
        buf.push(ev(ts, 1, RegistryEtwOp::Set, "v"));
    std::vector<RegistryCandidate> held{cand("changed", "v", 4, 4, 80, 95)};
    const auto batch = buf.snapshot();
    buf.retire(batch.last_seq, [&](const RegistryEtwEvent& e) {
        return release_event(e, retention_watermark(roots), held);
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

TEST_CASE("record keys are length-framed and never carry a NUL", "[tar][registry][pure]") {
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

TEST_CASE("cursor and baseline codecs", "[tar][registry][pure]") {
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
    for (const char* bad : {"", "garbage", "{\"v\":2}", "{\"v\":1}", "[]"})
        CHECK(decode_registry_cursor(std::string(bad)).malformed);
    // a cursor written before `skipped` existed decodes with the set empty
    auto older = nlohmann::json::parse(json);
    older["roots"]["HKLM\\R"].erase("skipped");
    CHECK(decode_registry_cursor(older.dump()).roots.at("HKLM\\R").skipped.empty());
    // a cursor written before window_base, held and loss existed (the key-watch-only source)
    // decodes as present and not malformed -- a malformed one would re-baseline every root
    auto v1 = nlohmann::json::parse(json);
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
    // an unknown field is ignored, so a later build can add state to this v1 cursor
    auto j = nlohmann::json::parse(json);
    j["later_field"] = nlohmann::json::array({1, 2});
    CHECK_FALSE(decode_registry_cursor(j.dump()).malformed);
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

TEST_CASE("registry schema constants agree with the registry", "[tar][registry][pure]") {
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
          "[tar][registry]") {
    CHECK(make_registry_cursor_source() == nullptr);
    CHECK(make_cursor_sources().size() == 2);
}
#endif

// ═══════════════════════════════════════════════════════════════════════════
// collect() over an injected reader
// ═══════════════════════════════════════════════════════════════════════════

namespace {

struct TestDb {
    TarDatabase db;
    fs::path path;
    ~TestDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        for (const char* sfx : {"", "-wal", "-shm", "-journal"})
            fs::remove(fs::path{path.string() + sfx}, ec);
    }
};

TestDb make_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_registry_");
    auto r = TarDatabase::open(tmp);
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
    bool etw{true}; // the write-event session is delivering
    std::vector<std::string> sids;
    int ccs{1};
    std::set<std::string> unarmed;
    std::vector<std::vector<std::string>> watch_calls;
    std::shared_ptr<RegistryDirtyTable> dirty = std::make_shared<RegistryDirtyTable>();
    std::shared_ptr<RegistryEtwBuffer> buffer = std::make_shared<RegistryEtwBuffer>();
    int tick_commits{0};

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
        r.loaded_sids = [this] { return sids; };
        r.now_ts = [this] { return clock += 1000; }; // strictly increasing
        r.etw_running = [this] { return etw; };
        r.session_loss = [this] { return loss; };
        r.current_control_set = [this] { return ccs; };
        r.watch_roots = [this](const std::vector<std::string>& roots) { watch_calls.push_back(roots); };
        r.root_armed = [this](const std::string& root) { return !unarmed.contains(root); };
        r.rearm = [this](const std::string& root) { return !unarmed.contains(root); };
        r.start = [] {};
        r.stop = [] {};
        r.tick_committed = [this] { ++tick_commits; };
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

CursorCollectResult tick(TarDatabase& db, CursorSource& src) {
    const auto cur = db.get_cursor("registry");
    REQUIRE(cur.has_value());
    return src.collect(db, *cur);
}

QueryResult q(TarDatabase& db, const std::string& sql) {
    auto r = db.execute_query(sql);
    REQUIRE(r.has_value());
    return *r;
}

std::int64_t count_rows(TarDatabase& db) {
    return std::stoll(q(db, "SELECT COUNT(*) FROM registry_live").rows.at(0).at(0));
}

RegistryCursor read_cursor(TarDatabase& db) {
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
std::size_t tick_settled(TarDatabase& db, Fake& f, CursorSource& src) {
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
          "[tar][registry][lifecycle]") {
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
    CHECK(f.tick_commits == 1);

    // A change under a notify burst is HELD with the burst's window (first notify and last,
    // each +/- 1 s): nothing is written yet, and only that root's baseline is rewritten.
    f.clock = T0 + 100 * SEC;
    f.reads[kRoot] = svc(2);
    burst(f, kRoot, T0 + 97 * SEC, T0 + 98 * SEC);
    const auto second = tick(t.db, *src);
    CHECK(second.outcome == CursorOutcome::Advanced);
    CHECK(second.events_emitted == 0);
    CHECK(count_rows(t.db) == 0);
    const std::int64_t read_end = f.clock; // the Fake's last now_ts(): the end of that read
    const auto cur = read_cursor(t.db);
    REQUIRE(cur.held.size() == 1);
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

TEST_CASE("registry source: a pushed event attributes by correlation; two pids are ambiguous",
          "[tar][registry][lifecycle]") {
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

TEST_CASE("registry source: with the session down a change lands as attr:off and the method is notify",
          "[tar][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    f.etw = false;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    const auto held = baseline_then_change(t, f, *src, 1, 2);
    src->push_event_for_test(ev(held.window_lo + SEC / 2, 812, RegistryEtwOp::Set, "Start")); // never used
    f.clock = T0 + 300 * SEC;
    tick(t.db, *src);
    const auto rows = q(t.db, "SELECT actor_pid, detail FROM registry_live");
    REQUIRE(rows.rows.size() == 1);
    CHECK(rows.rows[0][0] == "0");
    CHECK(rows.rows[0][1] == "attr:off");
    CHECK(t.db.get_config("registry_capture_method", "") == "notify");
}

TEST_CASE("registry source: the buffer keeps events newer than the watermark, then releases them",
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
    auto t = make_db();
    Fake f;
    auto src = make_registry_cursor_source(scope1(), f.reader());
    const auto held = baseline_then_change(t, f, *src, 1, 2);
    src->push_event_for_test(ev(held.window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Start", 4, 4, "a.exe"));
    const std::string cursor_before = *t.db.get_cursor("registry").value();
    const std::string baseline_before = *t.db.try_get_state("registry:" + kRoot).value();
    const auto buffered = src->buffer_for_test().size();
    const int commits_before = f.tick_commits;

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
    CHECK(f.tick_commits == commits_before);          // and no housekeeping for a tick that did not commit
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
    // the key is the diff's identity, whatever the replay attributed
    CHECK(rows.rows[0][2] ==
          registry_diff_record_key(held.source, held.observed_at, held.action, held.key, held.value));
    // the loss counter was not absorbed by the failed tick: the replay reports it, once
    const auto gaps = q(t.db, "SELECT detail FROM registry_live WHERE record_key LIKE 'gap:loss:%'");
    REQUIRE(gaps.rows.size() == 1);
    CHECK(gaps.rows[0][0] == "gap:loss:3");
}

TEST_CASE("registry source: lost cursor; restart; baseline loss; storage errors",
          "[tar][registry][lifecycle]") {
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
        // The change is held like any other; the writer's events were never seen, and the row
        // says that rather than naming nobody quietly.
        f2.clock = T0 + 600 * SEC;
        tick(t.db, *src2);
        const auto rows = q(t.db, "SELECT action, detail, source FROM registry_live ORDER BY id");
        REQUIRE(rows.rows.size() == 2);
        CHECK(rows.rows[0][0] == "capture_gap");
        CHECK(rows.rows[0][1].find("gap:restart") == 0);
        CHECK_THAT(rows.rows[0][1], ContainsSubstring("writers were never observed"));
        CHECK(rows.rows[1][0] == "changed");
        CHECK(rows.rows[1][1] == "attr:lost-restart");
        CHECK(rows.rows[1][2] == "reconcile"); // no notify survives a restart
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
        REQUIRE(t.db.execute_sql("DELETE FROM tar_state WHERE collector LIKE 'registry:%'"));
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
        REQUIRE(sqlite3_exec(h, "ALTER TABLE tar_state RENAME TO tar_state_away", nullptr, nullptr,
                             nullptr) == SQLITE_OK);
        f.dirty->mark(kRoot, f.clock);
        f.clock += 10 * SEC;
        CHECK_THROWS_AS(tick(t.db, *src), IncompleteCaptureError);
        sqlite3_exec(h, "ALTER TABLE tar_state_away RENAME TO tar_state", nullptr, nullptr, nullptr);
        sqlite3_close(h);
    }
}

TEST_CASE("registry source: disable discards the paused window; re-enable re-baselines with a gap",
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
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
}

TEST_CASE("registry source: kernel loss and a failed loss query are loss, reported once",
          "[tar][registry][lifecycle]") {
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

TEST_CASE("registry source: read statuses; status keys; fair root scheduling",
          "[tar][registry][lifecycle]") {
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
    }

    SECTION("attribution counters and the event count accumulate across ticks") {
        const auto held = baseline_then_change(t, f, *src, 1, 2);
        src->push_event_for_test(ev(held.window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Start"));
        src->push_event_for_test(ev(held.window_lo + SEC / 2, 5, RegistryEtwOp::Set, "Unrelated"));
        f.clock = T0 + 300 * SEC;
        tick(t.db, *src);
        CHECK(t.db.get_config("registry_attr_attributed", "") == "1");
        CHECK(t.db.get_config("registry_etw_events", "") == "2");
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
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
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
          "[tar][registry][lifecycle]") {
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
    return [value = fold_value_name(value), op](const RegistryEtwEvent& e) {
        return e.pid == ::GetCurrentProcessId() && e.op == op && fold_value_name(e.value) == value;
    };
}

} // namespace

TEST_CASE("registry live: set, change and delete through a pre-opened handle are attributed to this process",
          "[tar][registry][windows]") {
    const std::string leaf = "yuzu_test_reg_" + salt();
    TestKey key(leaf);
    if (key.create() != ERROR_SUCCESS)
        SKIP("cannot write HKLM (not elevated)");
    LiveRun run("SOFTWARE\\" + leaf); // the handle above was opened BEFORE start()
    tick(run.t.db, *run.src); // baseline
    if (std::stoi(run.t.db.get_config("registry_watch_roots", "0")) == 0)
        FAIL("the watch did not arm");
    if (run.t.db.get_config("registry_capture_method", "") != "notify+etw")
        SKIP("ETW session unavailable (not elevated)");

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
          "[tar][registry][windows]") {
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

TEST_CASE("registry live: stop leaves no ETW session behind", "[tar][registry][windows]") {
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
    if (!etw_running())
        SKIP("ETW session unavailable (not elevated)");
    REQUIRE(session_exists()); // the positive control: the lookup does find a running session
    src->stop();
    CHECK_FALSE(session_exists());
    CHECK_FALSE(etw_running());
    REQUIRE_NOTHROW(src->stop()); // idempotent
    CHECK_FALSE(session_exists());
}

TEST_CASE("registry live: a deleted and recreated root re-arms (R13)", "[tar][registry][windows]") {
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
          "[tar][registry][windows]") {
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
          "[tar][registry][windows]") {
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
          "[tar][registry][windows]") {
    {
        auto src = make_registry_cursor_source(RegistryScope{{"SOFTWARE\\yuzu_test_reg_none"}, {}},
                                         make_windows_registry_reader());
        TestDb t = make_db();
        src->start(t.db);
        REQUIRE_NOTHROW(src->stop());
        REQUIRE_NOTHROW(src->stop()); // idempotent
    } // ~RegistryCursorSource() after stop() must neither throw nor hang
}

#endif // _WIN32
