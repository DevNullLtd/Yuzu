/**
 * test_component_fs_win.cpp -- tests for the Windows leg of the component_inventory filesystem seam
 * (agents/plugins/component_inventory/src/component_fs_win.cpp, component_legs_win.hpp).
 *
 * TWO LAYERS.
 *   - Every OS: the pure decisions of component_legs_win.hpp over plain values and an in-memory tree.
 *     No Windows header, no filesystem, no clock: the lossless name conversion, the path forms, the
 *     Program Files roots and the WindowsApps exclusion, the fixed-volume rule, the record-type rule,
 *     the directory-record parser and the listing built from it (cap, truncation, order, a malformed
 *     batch), the FILETIME conversion and the ranged-read loop.
 *   - Windows only: the real leg over a real salted temporary tree (a junction, a symbolic link,
 *     non-ASCII and unpaired-surrogate names, a capped listing, ranged reads, change detection) and
 *     the live known-folder roots. The no-reparse guarantee is a property of the kernel's name
 *     resolution, so it can only be shown against a real junction; every race is staged in explicit
 *     steps (list, then replace, then the second call), never by timing.
 *
 * PROVENANCE. SYNTHETIC: no Windows capture is committed with this change. Every directory batch below
 * is built in the test to the documented FILE_ID_BOTH_DIR_INFO layout (the offsets are the ones
 * component_legs_win.hpp names; component_fs_win.cpp static_asserts them against the SDK struct on the
 * host that compiles it, so a wrong offset is a build failure there, not a silent misread here). The
 * attribute values are the documented FILE_ATTRIBUTE_* constants. The real-tree cases on Windows are
 * the first contact with a live volume.
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - typing a reparse point from FILE_ATTRIBUTE_DIRECTORY before FILE_ATTRIBUTE_REPARSE_POINT (a junction
 *    carries both) fails the attribute table: a junction would be listed through.
 *  - replacing WTF-8 with a lossy conversion fails the unpaired-surrogate cases: the listed name would
 *    not open the file it came from.
 *  - treating a failed or malformed batch as the end of the directory fails the error cases: a
 *    half-read directory would read as a whole one.
 *  - dropping the cut at max_dir_entries, or setting `truncated` without a further record, fails the
 *    cap cases.
 *  - accepting a drive root, a UNC path or a repeated root in windows_candidate_roots fails the roots
 *    case: one walk could spend its entry budget on a whole drive.
 *  - dropping a UNC root without counting it, or a relative / empty / drive-root path without setting
 *    mount_table_unreadable, fails the candidate-count cases and the no-silent-supported case: a Program
 *    Files tree that was never walked would read as a clean supported answer.
 *  - counting a volume whose type cannot be told (UNKNOWN, NO_ROOT_DIR) as a skipped network drive, or
 *    folding the three DriveClass answers into a bool, fails the volume-rule cases: an all-dropped host
 *    would answer supported with zero rows and one informational token.
 *  - dropping the volume_is_fixed test before an open (in either shell function), or testing it once at
 *    planning only, fails the per-open case on Windows (the staged fixed-then-not-fixed step) and, on
 *    every OS, the volume_is_fixed truth table the shell is a one-line call of.
 *  - comparing the WindowsApps path case-sensitively fails the exclusion case.
 *  - a windows_walk_policy that excludes nothing fails both WindowsApps cases, which build their policy
 *    from it: it is the function the plugin hands the walk for `scan` and for `native`, so the plugin
 *    cannot drop the exclusion without this builder changing.
 *  - treating a failed known-folder lookup as an empty host (supported, no rows) fails the lookup case.
 *  - dropping `policy` from scan()'s call to walk() (or from answer_scan's call to scan()) fails the scan
 *    case: WindowsApps would be listed, nothing counted, and the status row would carry no token.
 *  - opening a file by its joined path (a path-resolving open) fails the junction cases on Windows: the
 *    junction would be followed and the secret under its target opened.
 *  - dropping the size or last-write comparison from unchanged() fails the resize and rewrite cases.
 */
#include <catch2/catch_test_macros.hpp>

#include "component_fixture_tree.hpp" // build_zip and the in-memory FsOps the scan case runs over
#include "component_legs_win.hpp"
#include "component_native_parsers.hpp" // is_windows_native_candidate: the walk policy the WindowsApps case uses
#include "component_scan.hpp"           // answer_scan: the scan path the same exclusion must reach
#include "component_walk.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "test_helpers.hpp"              // yuzu::test::TempDir
#include "win_junction_test_support.hpp"  // yuzu::test::create_junction / JunctionCleanup

#include <filesystem>
#include <fstream>
#endif

using namespace yuzu::component_inventory;
using Type = DirEntry::Type;

namespace {

// ---- byte helpers (SYNTHETIC records in the FILE_ID_BOTH_DIR_INFO layout) ----

constexpr std::uint32_t kAttrNormal = 0x00000080;
constexpr std::uint32_t kAttrArchive = 0x00000020;

struct Rec {
    std::u16string name;
    std::uint32_t attrs{kAttrArchive};
    std::uint64_t id{0};
};

void set32(std::string& b, std::size_t at, std::uint32_t v) {
    std::memcpy(b.data() + at, &v, sizeof(v)); // the host is little-endian, as is every Windows target
}

void set64(std::string& b, std::size_t at, std::uint64_t v) {
    std::memcpy(b.data() + at, &v, sizeof(v));
}

/// One record: the fixed part of 104 bytes, the name, padded to 8. `last` writes NextEntryOffset 0.
[[nodiscard]] std::string record(const Rec& r, bool last) {
    const std::size_t name_bytes = r.name.size() * sizeof(char16_t);
    const std::size_t padded = (kDirInfoFileName + name_bytes + 7) & ~std::size_t{7};
    std::string b(padded, '\0');
    set32(b, kDirInfoNextEntryOffset, last ? 0 : static_cast<std::uint32_t>(padded));
    set32(b, kDirInfoFileAttributes, r.attrs);
    set32(b, kDirInfoFileNameLength, static_cast<std::uint32_t>(name_bytes));
    set64(b, kDirInfoFileId, r.id);
    if (name_bytes != 0)
        std::memcpy(b.data() + kDirInfoFileName, r.name.data(), name_bytes);
    return b;
}

[[nodiscard]] std::string batch(const std::vector<Rec>& recs) {
    std::string out;
    for (std::size_t i = 0; i < recs.size(); ++i)
        out += record(recs[i], i + 1 == recs.size());
    return out;
}

[[nodiscard]] std::span<const std::byte> bytes_of(const std::string& s) {
    return std::as_bytes(std::span<const char>{s.data(), s.size()});
}

/// A batch source that serves `batches` in order, then the end of the directory; `fail_at` makes that
/// call fail instead.
[[nodiscard]] DirBatchSource serve(std::vector<std::string> batches, std::optional<std::size_t> fail_at = {}) {
    struct State {
        std::vector<std::string> batches;
        std::size_t next{0};
        std::optional<std::size_t> fail_at;
    };
    auto st = std::make_shared<State>();
    st->batches = std::move(batches);
    st->fail_at = fail_at;
    return [st]() -> std::optional<std::span<const std::byte>> {
        const std::size_t n = st->next++;
        if (st->fail_at && *st->fail_at == n)
            return std::nullopt;
        if (n >= st->batches.size())
            return std::span<const std::byte>{};
        return bytes_of(st->batches[n]);
    };
}

[[nodiscard]] Rec dot(std::u16string_view n) {
    return Rec{std::u16string(n), 0x10, 1};
}

[[nodiscard]] std::vector<std::string> names_of(const ListResult& r) {
    std::vector<std::string> out;
    for (const auto& e : r.entries)
        out.push_back(e.name);
    return out;
}

[[nodiscard]] std::map<std::string, Type> by_name(const ListResult& r) {
    std::map<std::string, Type> m;
    for (const auto& e : r.entries)
        m[e.name] = e.type;
    return m;
}

} // namespace

// ---- names ----

TEST_CASE("component_legs_win: WTF-8 round-trips every UTF-16 sequence, unpaired surrogates included",
          "[component_inventory][fs_win]") {
    const std::vector<std::u16string> units = {
        u"",
        u"plain.jar",
        u"pr\u00F6gram",                  // two-byte
        u"\u65E5\u672C.jar",              // three-byte
        u"x\U0001F600y",                  // a surrogate pair: one four-byte sequence
        std::u16string{u"lone"} + static_cast<char16_t>(0xD800) + u".jar", // unpaired high
        std::u16string{u"lone"} + static_cast<char16_t>(0xDFFF) + u".jar", // unpaired low
        std::u16string{static_cast<char16_t>(0xDC00), static_cast<char16_t>(0xD800)}, // low then high: no pair
        std::u16string{static_cast<char16_t>(0xD800), static_cast<char16_t>(0xD800), static_cast<char16_t>(0xDC00)},
    };
    for (const auto& u : units) {
        const std::string w = wtf8_from_utf16(u);
        const auto back = utf16_from_wtf8(w);
        REQUIRE(back.has_value());
        CHECK(*back == u);
    }
    // Well-formed text is plain UTF-8, byte for byte.
    CHECK(wtf8_from_utf16(u"pr\u00F6gram") == "pr\xC3\xB6gram");
    CHECK(wtf8_from_utf16(u"\U0001F600") == "\xF0\x9F\x98\x80");
    // An unpaired surrogate is its own three-byte sequence, never U+FFFD.
    CHECK(wtf8_from_utf16(std::u16string{static_cast<char16_t>(0xD800)}) == "\xED\xA0\x80");
}

TEST_CASE("component_legs_win: WTF-8 decoding refuses what the encoder cannot have written",
          "[component_inventory][fs_win]") {
    for (const std::string_view bad : {
             std::string_view{"\x80"},                          // a stray continuation byte
             std::string_view{"\xC3"},                          // a truncated two-byte sequence
             std::string_view{"\xE6\x97"},                      // a truncated three-byte sequence
             std::string_view{"\xF0\x9F\x98"},                  // a truncated four-byte sequence
             std::string_view{"\xC0\x80"},                      // overlong NUL
             std::string_view{"\xC1\xBF"},                      // overlong
             std::string_view{"\xE0\x80\x80"},                  // overlong three-byte
             std::string_view{"\xF0\x80\x80\x80"},              // overlong four-byte
             std::string_view{"\xF4\x90\x80\x80"},              // past U+10FFFF
             std::string_view{"\xF8\x88\x80\x80\x80"},          // a five-byte form
             std::string_view{"\xFF"},                          // never a UTF-8 byte
             std::string_view{"\xED\xA0\x80\xED\xB0\x80"},      // a surrogate pair written as two three-byte forms
             std::string_view{"a\xC3(b"},                       // a sequence cut by a non-continuation byte
         }) {
        INFO(std::string(bad));
        CHECK_FALSE(utf16_from_wtf8(bad).has_value());
    }
    // Two lone high surrogates in a row are two lone units, not a pair, and decode.
    CHECK(utf16_from_wtf8("\xED\xA0\x80\xED\xA0\x80").has_value());
}

// ---- paths ----

TEST_CASE("component_legs_win: a native path becomes the walk's form and back", "[component_inventory][fs_win]") {
    CHECK(walk_path_from_native("C:\\Program Files\\") == "C:/Program Files");
    CHECK(walk_path_from_native("C:\\Program Files\\\\") == "C:/Program Files");
    CHECK(walk_path_from_native("d:/Program Files (x86)") == "d:/Program Files (x86)");
    CHECK(walk_path_from_native("C:\\") == "C:/"); // a bare root keeps its one separator

    const auto wide = native_path_from_walk("C:/Program Files/app/lib.dll");
    REQUIRE(wide.has_value());
    CHECK(*wide == u"C:\\Program Files\\app\\lib.dll");

    // Only `X:/` plus something is a walk path; the open refuses the finer cases itself.
    for (const std::string_view bad : {std::string_view{""}, std::string_view{"C:"}, std::string_view{"C:/"},
                                       std::string_view{"/opt/app"}, std::string_view{"app/lib.dll"},
                                       std::string_view{"//server/share/x"}, std::string_view{"C:\\x"},
                                       std::string_view{"1:/x"}, std::string_view{"C:/a\0b", 6}})
        CHECK_FALSE(native_path_from_walk(bad).has_value());
    CHECK_FALSE(native_path_from_walk("C:/x\xFF").has_value()); // not WTF-8
}

TEST_CASE("component_legs_win: paths with non-ASCII and unpaired-surrogate names round-trip",
          "[component_inventory][fs_win]") {
    const std::u16string lone = std::u16string{u"dir"} + static_cast<char16_t>(0xD800);
    for (const std::u16string& name : {std::u16string{u"pr\u00F6gram"}, std::u16string{u"\u65E5\u672C"},
                                       std::u16string{u"\U0001F600"}, lone}) {
        const std::string walk = "C:/Program Files/" + wtf8_from_utf16(name) + "/lib.dll";
        const auto wide = native_path_from_walk(walk);
        REQUIRE(wide.has_value());
        CHECK(*wide == u"C:\\Program Files\\" + name + u"\\lib.dll");
        // And back: the name the walk lists is the name the open will be given.
        const std::string again = walk_path_from_native(wtf8_from_utf16(*wide));
        CHECK(again == walk);
    }
}

// ---- roots, exclusions and the volume rule ----

TEST_CASE("component_legs_win: the roots are both Program Files trees in walk order and never a drive root",
          "[component_inventory][fs_win]") {
    CHECK(windows_candidate_roots("C:\\Program Files", "C:\\Program Files (x86)").roots ==
          std::vector<std::string>{"C:/Program Files", "C:/Program Files (x86)"});
    // A trailing separator is dropped; a second drive is a second root.
    CHECK(windows_candidate_roots("D:\\Program Files\\", "C:\\Program Files (x86)\\").roots ==
          std::vector<std::string>{"D:/Program Files", "C:/Program Files (x86)"});

    // A drive root is no root at all, and the other root is still offered.
    CHECK(windows_candidate_roots("C:\\", "C:\\Program Files (x86)").roots == std::vector<std::string>{"C:/Program Files (x86)"});
    CHECK(windows_candidate_roots("C:\\Program Files", "D:/").roots == std::vector<std::string>{"C:/Program Files"});
    for (const auto& root : windows_candidate_roots("C:\\", "D:\\").roots)
        FAIL("a drive root became a root: " << root);

    // The same tree twice (a 32-bit view, a spelling that differs only in case) is one root, and a
    // repeat is the one thing left out without a count: nothing is lost by it.
    const Targets twice = windows_candidate_roots("C:\\Program Files", "c:\\program files");
    CHECK(twice.roots == std::vector<std::string>{"C:/Program Files"});
    CHECK(twice.roots_network_skipped == 0);
    CHECK_FALSE(twice.mount_table_unreadable);
}

TEST_CASE("component_legs_win: every candidate that is not walked is counted or constrains the answer",
          "[component_inventory][fs_win]") {
    using Kind = KnownFolderPath;
    // The classification: a UNC path is network; a drive path is a root; everything else cannot be walked.
    CHECK(classify_known_folder_path("C:\\Program Files") == Kind::root);
    CHECK(classify_known_folder_path("c:/Program Files/") == Kind::root);
    CHECK(classify_known_folder_path("\\\\server\\share\\pf") == Kind::network);
    CHECK(classify_known_folder_path("//server/share") == Kind::network);
    for (const char* odd : {"", "Program Files", "\\Program Files", "C:", "C:\\", "D:/", "\\\\", "\\\\\\x",
                            "\\\\?\\C:\\Program Files", "\\\\.\\C:\\Program Files", "C;\\Program Files"}) {
        INFO("path: " << odd);
        CHECK(classify_known_folder_path(odd) == Kind::unnameable); // never network, never a root
    }

    // A UNC path is a counted network root, not a silent drop.
    const Targets unc = windows_candidate_roots("\\\\srv\\share\\pf", "C:\\Program Files (x86)");
    CHECK(unc.roots == std::vector<std::string>{"C:/Program Files (x86)"});
    CHECK(unc.roots_network_skipped == 1);
    CHECK_FALSE(unc.mount_table_unreadable);
    const Targets both_unc = windows_candidate_roots("\\\\srv\\a", "\\\\srv\\b");
    CHECK(both_unc.roots.empty());
    CHECK(both_unc.roots_network_skipped == 2);

    // A path that names no walkable directory (empty, relative, a bare drive root) constrains.
    const std::vector<std::pair<const char*, const char*>> unnameable = {{"", "C:\\Program Files (x86)"},
                                                                        {"C:\\Program Files", "Program Files"},
                                                                        {"C:\\", "C:\\Program Files (x86)"},
                                                                        {"C:\\Program Files", "D:/"}};
    for (const auto& [a, b] : unnameable) {
        INFO(a << " | " << b);
        const Targets t = windows_candidate_roots(a, b);
        CHECK(t.mount_table_unreadable);
        CHECK(t.roots_network_skipped == 0);
    }
    // A candidate that is usable, with no UNC and no oddity, sets nothing.
    CHECK_FALSE(windows_candidate_roots("C:\\Program Files", "C:\\Program Files (x86)").mount_table_unreadable);
}

TEST_CASE("component_legs_win: WindowsApps is excluded by exact path, case-insensitively, and counted",
          "[component_inventory][fs_win]") {
    const std::vector<std::string> roots = {"C:/Program Files", "C:/Program Files (x86)"};
    const auto excluded = windows_excluded_dirs(roots);
    REQUIRE(excluded.size() == 2);
    CHECK(excluded[0] == "C:/Program Files/WindowsApps");
    CHECK(excluded[1] == "C:/Program Files (x86)/WindowsApps");

    CHECK(is_windows_excluded_dir(excluded, "C:/Program Files/WindowsApps"));
    CHECK(is_windows_excluded_dir(excluded, "C:/Program Files/windowsapps"));
    CHECK(is_windows_excluded_dir(excluded, "c:/PROGRAM FILES (X86)/WINDOWSAPPS"));
    // Exact path only: a sibling with the prefix, a child and the same name elsewhere are not it.
    CHECK_FALSE(is_windows_excluded_dir(excluded, "C:/Program Files/WindowsApps2"));
    CHECK_FALSE(is_windows_excluded_dir(excluded, "C:/Program Files/WindowsApps/Pkg"));
    CHECK_FALSE(is_windows_excluded_dir(excluded, "C:/Program Files/Vendor/WindowsApps"));
    CHECK_FALSE(is_windows_excluded_dir(excluded, "D:/Program Files/WindowsApps"));

    // Through the real walk: the directory is never listed, is counted once, and its sibling is read.
    std::map<std::string, std::vector<DirEntry>> tree;
    tree["C:/Program Files"] = {{"App", Type::dir}, {"windowsapps", Type::dir}, {"WindowsApps2", Type::dir}};
    tree["C:/Program Files/App"] = {{"lib.dll", Type::file}};
    tree["C:/Program Files/windowsapps"] = {{"Pkg", Type::dir}};
    tree["C:/Program Files/windowsapps/Pkg"] = {{"hidden.dll", Type::file}};
    tree["C:/Program Files/WindowsApps2"] = {{"other.dll", Type::file}};
    std::vector<std::string> listed;
    FsOps fs;
    fs.list = [&](const std::string& dir, std::size_t) {
        listed.push_back(dir);
        ListResult r;
        const auto it = tree.find(dir);
        if (it == tree.end())
            r.error = true;
        else
            r.entries = it->second;
        return r;
    };
    fs.now = [] { return std::chrono::steady_clock::time_point{}; };
    // The policy the plugin hands the walk (windows_walk_policy), with `native`'s candidate test.
    Targets one;
    one.roots = {"C:/Program Files"};
    WalkPolicy policy = windows_walk_policy(one);
    policy.is_candidate = &is_windows_native_candidate;

    const std::vector<std::string>& one_root = one.roots;
    const WalkResult w = walk(one_root, WalkLimits{}, fs, std::chrono::steady_clock::time_point::max(), policy);
    CHECK(w.stop == Stop::complete);
    CHECK(w.stats.dirs_excluded == 1);
    CHECK(std::ranges::find(listed, "C:/Program Files/windowsapps") == listed.end());
    CHECK(std::ranges::find(listed, "C:/Program Files/windowsapps/Pkg") == listed.end());
    std::vector<std::string> paths;
    for (const auto& c : w.candidates)
        paths.push_back(c.path);
    CHECK(paths == std::vector<std::string>{"C:/Program Files/App/lib.dll", "C:/Program Files/WindowsApps2/other.dll"});
}

TEST_CASE("component_legs_win: the scan keeps out of WindowsApps too and says so on a supported row",
          "[component_inventory][fs_win]") {
    namespace fx = yuzu::component_inventory::fixture;
    // Three Java archives: one in an application, one under WindowsApps (any case), one under a
    // sibling that only shares the prefix.
    const auto build = [] {
        fx::MemTree tree;
        const std::string jar = fx::build_zip({fx::stored("a.class", "x")}).bytes;
        tree.add_file("C:/Program Files/App/lib-1.0.jar", jar);
        tree.add_file("C:/Program Files/windowsapps/Pkg/hidden-2.0.jar", jar);
        tree.add_file("C:/Program Files/WindowsApps2/other-3.0.jar", jar);
        return tree;
    };
    const auto row_paths = [](const Answer& a) {
        std::vector<std::string> paths;
        for (const auto& r : a.res.rows)
            paths.push_back(r.path);
        return paths;
    };
    Targets t;
    t.roots = {"C:/Program Files"};
    const WalkPolicy policy = windows_walk_policy(t); // the scan's: Java archives, WindowsApps skipped

    fx::MemTree tree = build();
    const Answer a = answer_scan("windows", t, [&](const Targets&) { return tree.ops(); }, WalkLimits{}, policy);

    // Never listed, never opened, counted once; the finished walk is a supported row naming the skip.
    CHECK(a.res.stats.dirs_excluded == 1);
    CHECK(std::ranges::find(tree.listed, "C:/Program Files/windowsapps") == tree.listed.end());
    CHECK(std::ranges::find(tree.listed, "C:/Program Files/windowsapps/Pkg") == tree.listed.end());
    CHECK(tree.opens.count("C:/Program Files/windowsapps/Pkg/hidden-2.0.jar") == 0);
    CHECK(a.verdict.complete);
    CHECK(a.verdict.level == yuzu::shared::StatusLevel::supported);
    REQUIRE_FALSE(a.lines.empty());
    CHECK(a.lines[0] == "status|scan|supported|windows:component_inventory:package_tree_skipped");
    CHECK(row_paths(a) == std::vector<std::string>{"C:/Program Files/App/lib-1.0.jar",
                                                   "C:/Program Files/WindowsApps2/other-3.0.jar"});

    // The default policy excludes nothing, which is every POSIX leg's scan: same tree, nothing counted.
    fx::MemTree open_tree = build();
    const Answer b = answer_scan("windows", t, [&](const Targets&) { return open_tree.ops(); }, WalkLimits{});
    CHECK(b.res.stats.dirs_excluded == 0);
    CHECK(b.lines[0] == "status|scan|supported|-");
    CHECK(row_paths(b).size() == 3);
}

TEST_CASE("component_legs_win: only STATUS_ACCESS_DENIED is a permission_denied listing",
          "[component_inventory][fs_win]") {
    CHECK(list_cause_from_ntstatus(0xC0000022u) == ListError::permission_denied); // STATUS_ACCESS_DENIED
    CHECK(list_cause_from_ntstatus(0xC000050Bu) == ListError::none); // STATUS_REPARSE_POINT_ENCOUNTERED
    CHECK(list_cause_from_ntstatus(0xC0000043u) == ListError::none); // STATUS_SHARING_VIOLATION
    CHECK(list_cause_from_ntstatus(0u) == ListError::none);          // never attempted
    CHECK(list_cause_from_ntstatus(0xC0001234u) == ListError::none); // unknown
}

TEST_CASE("component_legs_win: the scan reports a refused directory as dir_unreadable whatever the listing cause (#8739)",
          "[component_inventory][fs_win]") {
    namespace fx = yuzu::component_inventory::fixture;
    const auto run = [](ListError cause) {
        fx::MemTree tree;
        tree.add_file("C:/Program Files/App/lib-1.0.jar", fx::build_zip({fx::stored("a.class", "x")}).bytes);
        tree.add_file("C:/Program Files/Locked/x.jar", "x");
        FsOps ops = tree.ops();
        const auto inner = ops.list;
        ops.list = [inner, cause](const std::string& d, std::size_t cap) {
            if (d != "C:/Program Files/Locked")
                return inner(d, cap);
            ListResult r;
            r.error = true;
            r.cause = cause;
            return r;
        };
        Targets t;
        t.roots = {"C:/Program Files"};
        return answer_scan("windows", t, [&](const Targets&) { return ops; }, WalkLimits{});
    };
    // walk() has no permission_denied stop (only walk_ordered reads the cause); widening it is #8739.
    const Answer denied = run(ListError::permission_denied);
    REQUIRE_FALSE(denied.lines.empty());
    CHECK(denied.lines[0] == "status|scan|constrained|windows:component_inventory:dir_unreadable");
    const Answer other = run(ListError::none);
    REQUIRE_FALSE(other.lines.empty());
    CHECK(other.lines[0] == "status|scan|constrained|windows:component_inventory:dir_unreadable");
}

// ---- the roots from the two known-folder lookups ----

TEST_CASE("component_legs_win: a failed known-folder lookup walks nothing and says so, never an empty host",
          "[component_inventory][fs_win]") {
    int asked = 0;
    const DriveClassTest fixed = [&asked](char) {
        ++asked;
        return DriveClass::fixed;
    };
    using Folder = std::optional<std::string>;

    // Both lookups answered: both roots, in order, the flag clear.
    const Targets ok = windows_targets_from_known_folders(Folder{"C:\\Program Files"},
                                                          Folder{"C:\\Program Files (x86)"}, fixed);
    CHECK(ok.roots == std::vector<std::string>{"C:/Program Files", "C:/Program Files (x86)"});
    CHECK_FALSE(ok.mount_table_unreadable);
    CHECK(asked == 2);

    // Either lookup failing: no roots, the flag set, the drive test never asked.
    asked = 0;
    for (const auto& [pf, pf86] : {std::pair{Folder{}, Folder{"C:\\Program Files (x86)"}},
                                   std::pair{Folder{"C:\\Program Files"}, Folder{}},
                                   std::pair{Folder{}, Folder{}}}) {
        const Targets t = windows_targets_from_known_folders(pf, pf86, fixed);
        CHECK(t.roots.empty());
        CHECK(t.mount_table_unreadable);
    }
    // Both answered but neither can be walked (an empty string, a relative path): the same answer, and
    // the drive test is not asked about a path that names no drive.
    const Targets unusable = windows_targets_from_known_folders(Folder{"Program Files"}, Folder{""}, fixed);
    CHECK(unusable.roots.empty());
    CHECK(unusable.mount_table_unreadable);
    CHECK(asked == 0);

    // Two UNC paths are two counted network roots: nothing walked, and not a failed lookup either.
    const Targets unc = windows_targets_from_known_folders(Folder{"\\\\srv\\share\\pf"}, Folder{"\\\\srv\\share\\pf86"}, fixed);
    CHECK(unc.roots.empty());
    CHECK(unc.roots_network_skipped == 2);
    CHECK_FALSE(unc.mount_table_unreadable);
    CHECK(asked == 0);

    // A usable root on a drive that is not fixed is a skipped root, not a failed lookup.
    const Targets removable = windows_targets_from_known_folders(Folder{"D:\\Program Files"},
                                                                 Folder{"D:\\Program Files (x86)"},
                                                                 [](char) { return DriveClass::not_fixed; });
    CHECK(removable.roots.empty());
    CHECK(removable.roots_network_skipped == 2);
    CHECK_FALSE(removable.mount_table_unreadable);
}

// ---- the fixed-volume rule ----

TEST_CASE("component_legs_win: GetDriveTypeW's answer is fixed, not fixed, or unknown, and unknown is never not-fixed",
          "[component_inventory][fs_win]") {
    CHECK(drive_class_from_type(kDriveFixed) == DriveClass::fixed);
    for (const std::uint32_t t : {kDriveRemovable, kDriveRemote, kDriveCdrom, kDriveRamdisk}) {
        INFO("drive type " << t);
        CHECK(drive_class_from_type(t) == DriveClass::not_fixed);
    }
    // DRIVE_UNKNOWN (0), DRIVE_NO_ROOT_DIR (1) and anything undocumented cannot be told: they constrain.
    for (const std::uint32_t t : {std::uint32_t{0}, std::uint32_t{1}, std::uint32_t{7}, std::uint32_t{0xFFFFFFFFu}}) {
        INFO("drive type " << t);
        CHECK(drive_class_from_type(t) == DriveClass::unknown);
    }
}

TEST_CASE("component_legs_win: the drive of a walk path and the per-open fixed-volume gate",
          "[component_inventory][fs_win]") {
    CHECK(drive_of_walk_path("C:/Program Files") == 'C');
    CHECK(drive_of_walk_path("e:/Apps/lib.dll") == 'E'); // upper case: the shell asks about `E:\`
    for (const char* none : {"", "C:/", "C:", "/opt/app", "app", "//srv/share/x", "C:\\Program Files"}) {
        INFO("path: " << none);
        CHECK_FALSE(drive_of_walk_path(none).has_value());
    }

    // The gate the shell runs before every directory open and every file open: only `fixed` passes, and
    // it asks about the path's own drive, every time it is called.
    std::vector<char> asked;
    DriveClass answer = DriveClass::fixed;
    const DriveClassTest test = [&](char d) {
        asked.push_back(d);
        return answer;
    };
    CHECK(volume_is_fixed("c:/Program Files/App", test));
    CHECK(asked == std::vector<char>{'C'});
    answer = DriveClass::not_fixed;
    CHECK_FALSE(volume_is_fixed("c:/Program Files/App", test)); // the drive stopped being fixed between two opens
    answer = DriveClass::unknown;
    CHECK_FALSE(volume_is_fixed("c:/Program Files/App", test)); // an unreadable type is a refusal, not a pass
    CHECK(asked == std::vector<char>{'C', 'C', 'C'});           // asked again at each call, never cached

    // A path that names no drive is refused without asking.
    asked.clear();
    answer = DriveClass::fixed;
    CHECK_FALSE(volume_is_fixed("//srv/share/x", test));
    CHECK_FALSE(volume_is_fixed("relative/path", test));
    CHECK(asked.empty());
}

TEST_CASE("component_legs_win: plan_windows_targets keeps fixed-drive roots in order and counts the others",
          "[component_inventory][fs_win]") {
    std::vector<char> asked;
    const DriveClassTest by_drive = [&asked](char drive) {
        asked.push_back(drive);
        if (drive == 'C' || drive == 'E')
            return DriveClass::fixed;
        return drive == 'Q' ? DriveClass::unknown : DriveClass::not_fixed;
    };
    const auto candidates = [](std::vector<std::string> roots) {
        Targets c;
        c.roots = std::move(roots);
        return c;
    };

    const Targets t = plan_windows_targets(candidates({"C:/Program Files", "Z:/Program Files", "e:/Apps", "D:/Program Files"}),
                                           by_drive);
    CHECK(t.roots == std::vector<std::string>{"C:/Program Files", "e:/Apps"}); // walk order kept
    CHECK(t.roots_network_skipped == 2);                                      // Z: (mapped) and D: (optical)
    CHECK(asked == std::vector<char>{'C', 'Z', 'E', 'D'});                    // asked about the upper-case letter
    CHECK(t.network_mounts.empty());
    CHECK(t.roots_link_skipped == 0);
    CHECK_FALSE(t.mount_table_unreadable);

    // A drive whose type cannot be told is NOT a skipped network drive: it constrains the answer, and an
    // unestablished root list walks nothing.
    const Targets unknown = plan_windows_targets(candidates({"C:/Program Files", "Q:/Program Files"}), by_drive);
    CHECK(unknown.mount_table_unreadable);
    CHECK(unknown.roots_network_skipped == 0);
    CHECK(unknown.roots.empty());

    // The counts and the flag the candidates already carry (a UNC root, an unnameable path) survive the vetting.
    Targets carried = candidates({"C:/Program Files"});
    carried.roots_network_skipped = 1;
    CHECK(plan_windows_targets(carried, by_drive).roots_network_skipped == 1);
    Targets flagged = candidates({"C:/Program Files"});
    flagged.mount_table_unreadable = true;
    const Targets still = plan_windows_targets(flagged, by_drive);
    CHECK(still.mount_table_unreadable);
    CHECK(still.roots.empty());

    // A candidate that does not name a drive cannot be asked about and is not walked: it constrains.
    asked.clear();
    const Targets odd = plan_windows_targets(candidates({"/opt/app", "app", "", "C:/Program Files"}), by_drive);
    CHECK(odd.mount_table_unreadable);
    CHECK(odd.roots.empty());
    CHECK(asked == std::vector<char>{'C'});

    // Nothing fixed: nothing walked, every root counted.
    const Targets none = plan_windows_targets(candidates({"C:/Program Files", "C:/Program Files (x86)"}),
                                              [](char) { return DriveClass::not_fixed; });
    CHECK(none.roots.empty());
    CHECK(none.roots_network_skipped == 2);
    CHECK_FALSE(none.mount_table_unreadable);
}

TEST_CASE("component_legs_win: a host whose every candidate was dropped never answers supported with nothing said",
          "[component_inventory][fs_win]") {
    namespace fx = yuzu::component_inventory::fixture;
    using Folder = std::optional<std::string>;
    const auto answer_for = [](const Folder& pf, const Folder& pf86, DriveClass drive, bool& walked) {
        const Targets t = windows_targets_from_known_folders(pf, pf86, [drive](char) { return drive; });
        fx::MemTree tree;
        return answer_scan("windows", t, [&](const Targets&) {
            walked = true;
            return tree.ops();
        }, WalkLimits{});
    };
    constexpr const char* kUnreadable = "status|scan|constrained|windows:component_inventory:mount_table_unreadable";
    constexpr const char* kNetwork = "status|scan|supported|windows:component_inventory:network_fs_skipped";

    struct Case {
        const char* what;
        Folder pf, pf86;
        DriveClass drive;
        const char* status;
        std::size_t roots_skipped;
    };
    const std::vector<Case> cases = {
        {"drive type cannot be told", Folder{"C:\\Program Files"}, Folder{"C:\\Program Files (x86)"}, DriveClass::unknown,
         kUnreadable, 0},
        {"both paths unnameable", Folder{"Program Files"}, Folder{""}, DriveClass::fixed, kUnreadable, 0},
        {"one UNC, one unnameable", Folder{"\\\\srv\\share"}, Folder{"C:\\"}, DriveClass::fixed, kUnreadable, 1},
        {"a lookup failed", Folder{}, Folder{"C:\\Program Files (x86)"}, DriveClass::fixed, kUnreadable, 0},
        // Informational by ruling, but never silent: the row names the skip and the count is reported.
        {"both UNC", Folder{"\\\\srv\\a"}, Folder{"\\\\srv\\b"}, DriveClass::fixed, kNetwork, 2},
        {"both on a network or optical drive", Folder{"D:\\Program Files"}, Folder{"D:\\Program Files (x86)"},
         DriveClass::not_fixed, kNetwork, 2},
    };
    for (const Case& c : cases) {
        INFO(c.what);
        bool walked = false;
        const Answer a = answer_for(c.pf, c.pf86, c.drive, walked);
        REQUIRE_FALSE(a.lines.empty());
        CHECK(a.lines[0] == c.status);
        CHECK(a.res.rows.empty());
        CHECK(a.roots_skipped == c.roots_skipped);
        // The invariant itself: no answer is supported with the bare `-` token and zero rows because the
        // plan dropped everything it was given.
        CHECK_FALSE((a.verdict.level == yuzu::shared::StatusLevel::supported && a.verdict.tokens.empty()));
        CHECK(walked == (std::string_view{c.status} == kNetwork)); // a constrained answer never reaches the filesystem
    }
}

// ---- records ----

TEST_CASE("component_legs_win: a reparse point is a link whatever else its attributes say",
          "[component_inventory][fs_win]") {
    constexpr std::uint32_t kHidden = 0x2, kSystem = 0x4, kReadOnly = 0x1, kOffline = 0x1000;
    CHECK(entry_type_from_attributes(kAttrReparsePoint) == Type::link);                     // a file symlink
    CHECK(entry_type_from_attributes(kAttrReparsePoint | kAttrDirectory) == Type::link);    // a junction, a dir symlink
    CHECK(entry_type_from_attributes(kAttrReparsePoint | kAttrDirectory | kHidden | kSystem) == Type::link);
    CHECK(entry_type_from_attributes(kAttrReparsePoint | kOffline) == Type::link);          // a cloud stub
    CHECK(entry_type_from_attributes(kAttrDirectory) == Type::dir);
    CHECK(entry_type_from_attributes(kAttrDirectory | kHidden | kSystem) == Type::dir);
    CHECK(entry_type_from_attributes(kAttrArchive) == Type::file);
    CHECK(entry_type_from_attributes(kAttrNormal) == Type::file);
    CHECK(entry_type_from_attributes(kReadOnly | kHidden) == Type::file);
    CHECK(entry_type_from_attributes(0) == Type::file);
    CHECK(entry_type_from_attributes(kAttrDevice) == Type::other);
}

TEST_CASE("component_legs_win: a batch gives name, type and file id, skips dot entries and sorts the listing",
          "[component_inventory][fs_win]") {
    const std::u16string lone = std::u16string{u"z"} + static_cast<char16_t>(0xD800) + u".jar";
    const std::string b = batch({
        dot(u"."),
        dot(u".."),
        Rec{u"b.jar", kAttrArchive, 22},
        Rec{u"lib", 0x10, 33},
        Rec{u"a.DLL", kAttrNormal, 11},
        Rec{u"junction", 0x10 | kAttrReparsePoint, 44},
        Rec{u"pr\u00F6gram.jar", kAttrArchive, 55},
        Rec{lone, kAttrArchive, 66},
    });
    const ListResult r = list_from_batches(serve({b}), 100);
    REQUIRE_FALSE(r.error);
    CHECK_FALSE(r.truncated);
    // Sorted by name bytes: upper case before lower, so a.DLL < b.jar < junction < lib < pr... < z...
    CHECK(names_of(r) == std::vector<std::string>{"a.DLL", "b.jar", "junction", "lib", "pr\xC3\xB6gram.jar",
                                                  wtf8_from_utf16(lone)});
    const auto types = by_name(r);
    CHECK(types.at("a.DLL") == Type::file);
    CHECK(types.at("junction") == Type::link);
    CHECK(types.at("lib") == Type::dir);
    std::map<std::string, std::uint64_t> ids;
    for (const auto& e : r.entries)
        ids[e.name] = e.file_id;
    CHECK(ids.at("a.DLL") == 11);
    CHECK(ids.at("b.jar") == 22);
    CHECK(ids.at("lib") == 33);
    CHECK(ids.at("junction") == 44);
    // The identity of the listed directory is not reported by this binding.
    CHECK(r.dev == 0);
    CHECK(r.file_id == 0);
}

TEST_CASE("component_legs_win: an empty directory and one with only dot entries are clean and empty",
          "[component_inventory][fs_win]") {
    const ListResult none = list_from_batches(serve({}), 10);
    CHECK_FALSE(none.error);
    CHECK(none.entries.empty());
    const ListResult dots = list_from_batches(serve({batch({dot(u"."), dot(u"..")})}), 10);
    CHECK_FALSE(dots.error);
    CHECK_FALSE(dots.truncated);
    CHECK(dots.entries.empty());
}

TEST_CASE("component_legs_win: records across several batches are one listing", "[component_inventory][fs_win]") {
    const ListResult r = list_from_batches(
        serve({batch({dot(u"."), Rec{u"c.jar"}}), batch({Rec{u"a.jar"}, Rec{u"b.jar"}}), batch({Rec{u"d.jar"}})}), 10);
    REQUIRE_FALSE(r.error);
    CHECK(names_of(r) == std::vector<std::string>{"a.jar", "b.jar", "c.jar", "d.jar"});
}

TEST_CASE("component_legs_win: the per-directory cap cuts the listing and says so only when a record remained",
          "[component_inventory][fs_win]") {
    const std::string five = batch({Rec{u"a"}, Rec{u"b"}, Rec{u"c"}, Rec{u"d"}, Rec{u"e"}});

    const ListResult cut = list_from_batches(serve({five}), 3);
    CHECK_FALSE(cut.error);
    CHECK(cut.truncated);
    CHECK(cut.entries.size() == 3);

    const ListResult exact = list_from_batches(serve({five}), 5);
    CHECK_FALSE(exact.truncated); // exactly the cap, nothing past it
    CHECK(exact.entries.size() == 5);

    const ListResult roomy = list_from_batches(serve({five}), 50000);
    CHECK_FALSE(roomy.truncated);

    // The cap met at the end of a batch: a further real record in the next batch is a truncation, a
    // batch that holds only dot entries (or no further batch) is not.
    const std::string two = batch({Rec{u"a"}, Rec{u"b"}});
    const ListResult more = list_from_batches(serve({two, batch({Rec{u"c"}})}), 2);
    CHECK(more.truncated);
    CHECK(more.entries.size() == 2);
    const ListResult dots_after = list_from_batches(serve({two, batch({dot(u"."), dot(u"..")})}), 2);
    CHECK_FALSE(dots_after.truncated);
    CHECK(dots_after.entries.size() == 2);
    const ListResult ends = list_from_batches(serve({two}), 2);
    CHECK_FALSE(ends.truncated);

    // Dot entries are never counted against the cap.
    const ListResult dotted = list_from_batches(serve({batch({dot(u"."), dot(u".."), Rec{u"a"}, Rec{u"b"}})}), 2);
    CHECK_FALSE(dotted.truncated);
    CHECK(dotted.entries.size() == 2);
}

TEST_CASE("component_legs_win: a failed or malformed batch is an error with no entries, never a short listing",
          "[component_inventory][fs_win]") {
    const auto is_error = [](const ListResult& r) {
        return r.error && r.entries.empty() && !r.truncated;
    };

    // The OS failing at the first call, and after a good batch.
    CHECK(is_error(list_from_batches(serve({}, 0), 10)));
    CHECK(is_error(list_from_batches(serve({batch({Rec{u"a.jar"}}), batch({Rec{u"b.jar"}})}, 1), 10)));

    const std::string good = batch({Rec{u"a.jar"}, Rec{u"b.jar"}});
    // A name length that is odd, zero, or runs past the batch.
    for (const std::uint32_t name_bytes : {std::uint32_t{3}, std::uint32_t{0}, std::uint32_t{4000}}) {
        std::string b = good;
        set32(b, kDirInfoFileNameLength, name_bytes);
        INFO("name length " << name_bytes);
        CHECK(is_error(list_from_batches(serve({b}), 10)));
    }
    // A next-entry offset that points past the batch, or back inside the record it belongs to.
    for (const std::uint32_t next : {std::uint32_t{100000}, std::uint32_t{8}, std::uint32_t{kDirInfoFileName - 1}}) {
        std::string b = good;
        set32(b, kDirInfoNextEntryOffset, next);
        INFO("next entry offset " << next);
        CHECK(is_error(list_from_batches(serve({b}), 10)));
    }
    // A batch too short to hold the fixed part of a record at all, and a chain whose next record is cut.
    CHECK(is_error(list_from_batches(serve({std::string(40, '\0')}), 10)));
    std::string cut = good;
    cut.resize(cut.size() - 8);
    CHECK(is_error(list_from_batches(serve({cut}), 10)));

    // No bad record is read past the batch: nothing before the error survives either.
    const ListResult r = list_from_batches(serve({good, std::string(40, '\0')}), 10);
    CHECK(is_error(r));
}

// ---- one file ----

TEST_CASE("component_legs_win: a FILETIME is Unix seconds, rounded toward the past", "[component_inventory][fs_win]") {
    CHECK(unix_seconds_from_filetime(116444736000000000ULL) == 0);
    CHECK(unix_seconds_from_filetime(116444736000000000ULL + 9999999) == 0); // not yet the next second
    CHECK(unix_seconds_from_filetime(116444736000000000ULL + 10000000) == 1);
    CHECK(unix_seconds_from_filetime(116444736000000000ULL + 17000000000000000ULL) == 1700000000);
    CHECK(unix_seconds_from_filetime(0) == -11644473600); // 1601-01-01, before the Unix epoch
}

TEST_CASE("component_legs_win: read_range serves exact ranges and a short answer only at end of file",
          "[component_inventory][fs_win]") {
    std::string file(100, '\0');
    for (std::size_t i = 0; i < file.size(); ++i)
        file[i] = static_cast<char>('a' + i % 26);
    std::size_t calls = 0;
    const auto reader = [&](std::size_t chunk) -> ReadOnce {
        return [&file, &calls, chunk](std::uint64_t off, char* buf, std::size_t len) -> std::optional<std::size_t> {
            ++calls;
            if (off >= file.size())
                return std::size_t{0};
            const std::size_t n = std::min({len, chunk, file.size() - static_cast<std::size_t>(off)});
            std::memcpy(buf, file.data() + off, n);
            return n;
        };
    };

    // Whatever size the OS answers in, the range is exact.
    for (const std::size_t chunk : {std::size_t{1}, std::size_t{7}, std::size_t{4096}}) {
        calls = 0;
        const auto head = read_range(0, 10, reader(chunk));
        REQUIRE(head.has_value());
        CHECK(*head == file.substr(0, 10));
        const auto mid = read_range(40, 25, reader(chunk));
        REQUIRE(mid.has_value());
        CHECK(*mid == file.substr(40, 25));
    }
    // A short read only at the end of the file; at or past it, an empty answer (not an error).
    const auto tail = read_range(95, 10, reader(4096));
    REQUIRE(tail.has_value());
    CHECK(*tail == file.substr(95));
    const auto at_end = read_range(100, 10, reader(4096));
    REQUIRE(at_end.has_value());
    CHECK(at_end->empty());
    const auto past = read_range(5000, 1, reader(4096));
    REQUIRE(past.has_value());
    CHECK(past->empty());
    calls = 0;
    const auto none = read_range(10, 0, reader(4096));
    REQUIRE(none.has_value());
    CHECK(none->empty());
    CHECK(calls == 0); // nothing asked, nothing read

    // An I/O error is an error, also after part of the range was read.
    const ReadOnce fails_at_once = [](std::uint64_t, char*, std::size_t) { return std::optional<std::size_t>{}; };
    CHECK_FALSE(read_range(0, 10, fails_at_once).has_value());
    std::size_t n = 0;
    const ReadOnce fails_second = [&n](std::uint64_t, char* buf, std::size_t len) -> std::optional<std::size_t> {
        if (n++ == 0) {
            std::memset(buf, 'x', 1);
            return std::size_t{1};
        }
        (void)len;
        return std::nullopt;
    };
    CHECK_FALSE(read_range(0, 10, fails_second).has_value());
}

TEST_CASE("component_legs_win: read_range refuses what it cannot serve whole instead of cutting it",
          "[component_inventory][fs_win]") {
    bool asked = false;
    const ReadOnce any = [&asked](std::uint64_t, char*, std::size_t) -> std::optional<std::size_t> {
        asked = true;
        return std::size_t{0};
    };
    CHECK_FALSE(read_range(0, kMaxReadAt + 1, any).has_value());                       // over the per-call bound
    CHECK(read_range(0, kMaxReadAt, any).has_value());                                 // exactly the bound is served
    asked = false;
    CHECK_FALSE(read_range(static_cast<std::uint64_t>(INT64_MAX) + 1, 1, any).has_value()); // past a signed offset
    CHECK_FALSE(read_range(static_cast<std::uint64_t>(INT64_MAX), 1, any).has_value());     // offset + len overflows it
    CHECK_FALSE(asked);                                                                // refused before any read
}

// ---- Windows only: the real leg over a real tree ----

#if defined(_WIN32)

namespace fs = std::filesystem;

namespace {

void write_file(const fs::path& p, const std::string& body) {
    std::ofstream f(p, std::ios::binary);
    f << body;
}

/// A salted scratch tree. `root` is canonical, so no component of it is a reparse point: the system
/// temp directory can itself be reached through one, and a leg that follows none would otherwise refuse
/// the test's own root.
struct WinTree {
    yuzu::test::TempDir tmp{"yuzu_test_cfw_"};
    fs::path root;

    WinTree() {
        REQUIRE(fs::create_directory(tmp.path));
        root = fs::canonical(tmp.path);
    }
};

[[nodiscard]] std::string walk_of(const fs::path& p) {
    return walk_path_from_native(wtf8_from_utf16(p.generic_u16string()));
}

/// The real leg over the real tree, with the volume test fixed to `fixed` so these cases do not depend
/// on the type of the drive the runner's temp directory happens to sit on; the live GetDriveTypeW wiring
/// has its own case below.
[[nodiscard]] FsOps real_ops() {
    return make_fs_ops(Targets{}, [](char) { return DriveClass::fixed; });
}

/// Nothing when `ec` is clear, SKIP when only a missing privilege stopped a symbolic link (no
/// developer mode on the runner), FAIL for anything else: a set-up defect must not read as a skip.
void require_link_or_skip(const std::error_code& ec) {
    if (!ec)
        return;
    if (ec.value() == static_cast<int>(ERROR_PRIVILEGE_NOT_HELD))
        SKIP("creating a symbolic link needs a privilege this account does not hold");
    FAIL("could not create a symbolic link: " << ec.message());
}

} // namespace

TEST_CASE("component_fs_win: a junction inside the tree is reported as a link and never listed through",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    const fs::path target = t.root / "target";
    REQUIRE(fs::create_directory(target));
    write_file(target / "secret.jar", "secret");
    write_file(t.root / "plain.jar", "plain");
    const fs::path link = t.root / "link";
    REQUIRE(yuzu::test::create_junction(link, target));
    yuzu::test::JunctionCleanup cleanup{link}; // declared after the tree: removes the junction first

    const FsOps ops = real_ops();
    const ListResult top = ops.list(walk_of(t.root), 100);
    REQUIRE_FALSE(top.error);
    const auto types = by_name(top);
    CHECK(types.at("link") == Type::link);
    CHECK(types.at("target") == Type::dir);
    CHECK(types.at("plain.jar") == Type::file);

    // Listing the junction itself is refused: nothing under its target is returned.
    const ListResult through = ops.list(walk_of(link), 100);
    CHECK(through.error);
    CHECK(through.entries.empty());

    // The whole walk: the junction is counted, the file behind it is reached once, by its real path.
    const std::vector<std::string> roots = {walk_of(t.root)};
    const WalkResult w = walk(roots, WalkLimits{}, ops, ops.now() + std::chrono::seconds(60));
    CHECK(w.stop == Stop::complete);
    CHECK(w.stats.links_skipped == 1);
    std::vector<std::string> found;
    for (const auto& c : w.candidates)
        found.push_back(c.path);
    std::ranges::sort(found);
    CHECK(found == std::vector<std::string>{walk_of(t.root / "plain.jar"), walk_of(target / "secret.jar")});
}

TEST_CASE("component_fs_win: a symbolic link inside the tree is reported as a link and never entered or opened",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    const fs::path target = t.root / "target";
    REQUIRE(fs::create_directory(target));
    write_file(target / "secret.jar", "secret");
    write_file(t.root / "real.jar", "real");

    std::error_code ec;
    fs::create_directory_symlink(target, t.root / "dlink", ec);
    require_link_or_skip(ec);
    fs::create_symlink(t.root / "real.jar", t.root / "flink.jar", ec);
    require_link_or_skip(ec);

    const FsOps ops = real_ops();
    const ListResult top = ops.list(walk_of(t.root), 100);
    REQUIRE_FALSE(top.error);
    const auto types = by_name(top);
    CHECK(types.at("dlink") == Type::link);
    CHECK(types.at("flink.jar") == Type::link);
    CHECK(types.at("real.jar") == Type::file);

    CHECK(ops.list(walk_of(t.root / "dlink"), 100).error);
    CHECK_FALSE(ops.open_file(walk_of(t.root / "dlink" / "secret.jar")).has_value());
    CHECK_FALSE(ops.open_file(walk_of(t.root / "flink.jar")).has_value()); // a link leaf is never opened
    CHECK(ops.open_file(walk_of(t.root / "real.jar")).has_value());        // the control
}

TEST_CASE("component_fs_win: a file reached only through a junction is never opened",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    const fs::path target = t.root / "target";
    REQUIRE(fs::create_directory(target));
    write_file(target / "secret.jar", "secret");
    const fs::path link = t.root / "link";
    REQUIRE(yuzu::test::create_junction(link, target));
    yuzu::test::JunctionCleanup cleanup{link};

    const FsOps ops = real_ops();
    CHECK_FALSE(ops.open_file(walk_of(link / "secret.jar")).has_value()); // through the junction: refused
    const auto direct = ops.open_file(walk_of(target / "secret.jar"));     // the same bytes by their real path
    REQUIRE(direct.has_value());
    CHECK(direct->size == 6);
    CHECK_FALSE(ops.open_file(walk_of(t.root / "absent.jar")).has_value());
    CHECK_FALSE(ops.open_file(walk_of(target)).has_value()); // a directory is not a file
}

TEST_CASE("component_fs_win: a directory swapped for a junction after its listing is refused",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    const fs::path dir = t.root / "dir";
    REQUIRE(fs::create_directory(dir));
    write_file(dir / "inside.jar", "inside");
    const fs::path victim = t.root / "victim";
    REQUIRE(fs::create_directory(victim));
    write_file(victim / "secret.jar", "secret");

    const FsOps ops = real_ops();
    const ListResult before = ops.list(walk_of(dir), 100);
    REQUIRE_FALSE(before.error);
    CHECK(names_of(before) == std::vector<std::string>{"inside.jar"});

    // The planter's step: the listed directory is replaced by a junction to the victim.
    fs::remove_all(dir);
    REQUIRE(yuzu::test::create_junction(dir, victim));
    yuzu::test::JunctionCleanup cleanup{dir};

    const ListResult after = ops.list(walk_of(dir), 100);
    CHECK(after.error);
    CHECK(after.entries.empty());
    CHECK_FALSE(ops.open_file(walk_of(dir / "secret.jar")).has_value());
}

TEST_CASE("component_fs_win: list honours the per-directory cap and reports truncation",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    for (const char* name : {"a.jar", "b.jar", "c.jar", "d.jar", "e.jar"})
        write_file(t.root / name, "x");
    const FsOps ops = real_ops();

    const ListResult cut = ops.list(walk_of(t.root), 3);
    CHECK_FALSE(cut.error);
    CHECK(cut.truncated);
    CHECK(cut.entries.size() == 3);

    const ListResult exact = ops.list(walk_of(t.root), 5);
    CHECK_FALSE(exact.truncated);
    CHECK(names_of(exact) == std::vector<std::string>{"a.jar", "b.jar", "c.jar", "d.jar", "e.jar"});

    CHECK_FALSE(ops.list(walk_of(t.root), 50000).truncated);
    // A directory that is not there, and one that is a file, are errors.
    CHECK(ops.list(walk_of(t.root / "absent"), 10).error);
    CHECK(ops.list(walk_of(t.root / "a.jar"), 10).error);
}

TEST_CASE("component_fs_win: read_at returns exact ranges and a short read only at end of file",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    std::string body(100, '\0');
    for (std::size_t i = 0; i < body.size(); ++i)
        body[i] = static_cast<char>('a' + i % 26);
    write_file(t.root / "lib.dll", body);

    const FsOps ops = real_ops();
    const auto view = ops.open_file(walk_of(t.root / "lib.dll"));
    REQUIRE(view.has_value());
    CHECK(view->size == 100);
    CHECK(view->mtime > 1600000000); // a real, recent last-write time as Unix seconds

    const auto head = view->read_at(0, 10);
    REQUIRE(head.has_value());
    CHECK(*head == body.substr(0, 10));
    const auto mid = view->read_at(37, 41);
    REQUIRE(mid.has_value());
    CHECK(*mid == body.substr(37, 41));
    const auto all = view->read_at(0, 100);
    REQUIRE(all.has_value());
    CHECK(*all == body);
    const auto tail = view->read_at(95, 10);
    REQUIRE(tail.has_value());
    CHECK(*tail == body.substr(95)); // five bytes: a short read only because the file ended
    const auto at_end = view->read_at(100, 10);
    REQUIRE(at_end.has_value());
    CHECK(at_end->empty());
    const auto past = view->read_at(1000000, 1);
    REQUIRE(past.has_value());
    CHECK(past->empty());
    const auto again = view->read_at(0, 10); // the positioned read leaves nothing behind
    REQUIRE(again.has_value());
    CHECK(*again == body.substr(0, 10));

    // A request over the per-call bound is refused, never cut.
    CHECK_FALSE(view->read_at(0, kMaxReadAt + 1).has_value());

    // An empty file is a view of size 0 that reads empty.
    write_file(t.root / "empty.dll", "");
    const auto empty = ops.open_file(walk_of(t.root / "empty.dll"));
    REQUIRE(empty.has_value());
    CHECK(empty->size == 0);
    const auto nothing = empty->read_at(0, 8);
    REQUIRE(nothing.has_value());
    CHECK(nothing->empty());
}

TEST_CASE("component_fs_win: unchanged() turns false after the file is rewritten or resized",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    const fs::path p = t.root / "lib.dll";
    const FsOps ops = real_ops();

    { // resized: a longer file
        write_file(p, "0123456789");
        const auto view = ops.open_file(walk_of(p));
        REQUIRE(view.has_value());
        CHECK(view->unchanged());
        {
            std::ofstream f(p, std::ios::binary | std::ios::app);
            f << "more";
        }
        CHECK_FALSE(view->unchanged());
    }
    { // resized: a shorter file
        write_file(p, "0123456789");
        const auto view = ops.open_file(walk_of(p));
        REQUIRE(view.has_value());
        fs::resize_file(p, 5);
        CHECK_FALSE(view->unchanged());
    }
    { // rewritten in place at the same size: only the last-write time tells. It is set outright rather
      // than waited for, so the case does not depend on the clock's tick.
        write_file(p, "0123456789");
        const auto view = ops.open_file(walk_of(p));
        REQUIRE(view.has_value());
        CHECK(view->unchanged());
        const auto before = fs::last_write_time(p);
        write_file(p, "ABCDEFGHIJ");
        fs::last_write_time(p, before + std::chrono::seconds(2));
        CHECK_FALSE(view->unchanged());
    }
    { // not touched: still unchanged however often it is asked
        write_file(p, "0123456789");
        const auto view = ops.open_file(walk_of(p));
        REQUIRE(view.has_value());
        CHECK(view->unchanged());
        CHECK(view->unchanged());
    }
}

TEST_CASE("component_fs_win: paths with non-ASCII and unpaired-surrogate names round-trip",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    const std::vector<std::u16string> dirs = {
        u"pr\u00F6gram",
        u"\u65E5\u672C",
        u"\U0001F600",
        std::u16string{u"lone"} + static_cast<char16_t>(0xD800), // an unpaired surrogate: NTFS allows it
        std::u16string{u"lone"} + static_cast<char16_t>(0xDFFF),
    };
    for (const auto& d : dirs) {
        const fs::path dir = t.root / std::wstring(d.begin(), d.end());
        REQUIRE(fs::create_directory(dir));
        write_file(dir / "lib.dll", "payload-" + wtf8_from_utf16(d).substr(0, 4));
    }

    const FsOps ops = real_ops();
    const ListResult top = ops.list(walk_of(t.root), 100);
    REQUIRE_FALSE(top.error);
    REQUIRE(top.entries.size() == dirs.size());
    for (const auto& d : dirs) {
        const std::string name = wtf8_from_utf16(d);
        const auto types = by_name(top);
        REQUIRE(types.contains(name)); // the listed name is the directory's own, not a lossy one
        CHECK(types.at(name) == Type::dir);

        // The name that was listed opens the directory it came from, and the file in it.
        const std::string dir_walk = walk_of(t.root) + "/" + name;
        const ListResult inside = ops.list(dir_walk, 100);
        REQUIRE_FALSE(inside.error);
        CHECK(names_of(inside) == std::vector<std::string>{"lib.dll"});
        const auto view = ops.open_file(dir_walk + "/lib.dll");
        REQUIRE(view.has_value());
        const auto bytes = view->read_at(0, 64);
        REQUIRE(bytes.has_value());
        CHECK(*bytes == "payload-" + name.substr(0, 4));
    }
}

TEST_CASE("component_fs_win: the walk over the real leg reaches the files and counts what it passes over",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    REQUIRE(fs::create_directories(t.root / "app" / "lib"));
    write_file(t.root / "app" / "lib" / "one.dll", "one");
    write_file(t.root / "app" / "lib" / "ignored.txt", "text");
    write_file(t.root / "app" / "two.DLL", "two");
    const fs::path target = t.root / "elsewhere";
    REQUIRE(fs::create_directory(target));
    write_file(target / "hidden.dll", "hidden");
    const fs::path link = t.root / "app" / "linked";
    REQUIRE(yuzu::test::create_junction(link, target));
    yuzu::test::JunctionCleanup cleanup{link};

    const FsOps ops = real_ops();
    WalkPolicy policy;
    policy.is_candidate = &is_windows_native_candidate; // `.DLL` and `.dll` are both candidates
    const std::vector<std::string> roots = {walk_of(t.root / "app")};
    const WalkResult w = walk(roots, WalkLimits{}, ops, ops.now() + std::chrono::seconds(60), policy);
    CHECK(w.stop == Stop::complete);
    CHECK(w.stats.links_skipped == 1);
    std::vector<std::string> found;
    for (const auto& c : w.candidates)
        found.push_back(c.path);
    std::ranges::sort(found);
    CHECK(found == std::vector<std::string>{walk_of(t.root / "app" / "lib" / "one.dll"), walk_of(t.root / "app" / "two.DLL")});
}

TEST_CASE("component_fs_win: a volume that is not fixed is refused at every open, not only at planning",
          "[runtime][component_inventory][fs_win]") {
    WinTree t;
    write_file(t.root / "a.jar", "x");
    const std::string dir = walk_of(t.root);
    const std::string file = walk_of(t.root / "a.jar");
    const char drive = static_cast<char>(std::toupper(static_cast<unsigned char>(dir[0])));

    // A volume that is not fixed, or whose type cannot be told, refuses the directory open and the file
    // open alike; the drive it is asked about is the path's own, once per open.
    for (const DriveClass c : {DriveClass::not_fixed, DriveClass::unknown}) {
        std::vector<char> asked;
        const FsOps ops = make_fs_ops(Targets{}, [&](char d) {
            asked.push_back(d);
            return c;
        });
        const ListResult listing = ops.list(dir, 100);
        CHECK(listing.error);
        CHECK(listing.entries.empty());
        CHECK_FALSE(ops.open_file(file).has_value());
        CHECK(asked == std::vector<char>{drive, drive});
    }

    // The staged step: the same leg, fixed when planned and used, then the drive stops being fixed
    // (SUBST, a disk swap): the next open is refused although nothing about the path changed.
    DriveClass now = DriveClass::fixed;
    const FsOps ops = make_fs_ops(Targets{}, [&](char) { return now; });
    REQUIRE_FALSE(ops.list(dir, 100).error);
    REQUIRE(ops.open_file(file).has_value());
    now = DriveClass::not_fixed;
    CHECK(ops.list(dir, 100).error);
    CHECK_FALSE(ops.open_file(file).has_value());

    // The live wiring (GetDriveTypeW through drive_class_from_type) opens this tree when its drive is fixed.
    const wchar_t root[] = {static_cast<wchar_t>(drive), L':', L'\\', L'\0'};
    if (GetDriveTypeW(root) != DRIVE_FIXED)
        SKIP("the temporary directory is not on a fixed drive");
    const FsOps live = make_fs_ops(Targets{});
    CHECK_FALSE(live.list(dir, 100).error);
    CHECK(live.open_file(file).has_value());
}

TEST_CASE("component_fs_win: the live roots are the Program Files trees on fixed drives",
          "[runtime][component_inventory][fs_win]") {
    // The shell's known-folder lookup, not the environment: a read of the host's own configuration.
    for (const Targets& t : {scan_targets(), scan_native_targets()}) {
        CHECK_FALSE(t.mount_table_unreadable);
        CHECK(t.roots_link_skipped == 0);
        CHECK(t.network_mounts.empty());
        REQUIRE_FALSE(t.roots.empty());
        for (const auto& r : t.roots) {
            INFO(r);
            CHECK(r.size() > 3);
            CHECK(r[1] == ':');
            CHECK(r[2] == '/');
            CHECK(r.find('\\') == std::string::npos); // the walk's form
        }
    }
}

#endif // _WIN32
